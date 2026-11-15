"""Policy CRUD and validation tests."""


def make_payload(**overrides):
    payload = {
        "name": "Family baseline",
        "description": "Baseline filtering for the family.",
        "default_policy": "allow",
        "allowlist": ["important-override.example"],
        "blocklist": ["tracker.example.com"],
        "category_allow": ["education"],
        "category_block": ["gambling", "adult-content"],
        "enabled": True,
    }
    payload.update(overrides)
    return payload


def create(client, **overrides):
    status, body = client.post("/api/policies", make_payload(**overrides))
    assert status == 201, body
    return body


def test_create_and_get(client):
    policy = create(client)
    assert policy["name"] == "Family baseline"
    assert policy["default_policy"] == "allow"
    assert policy["enabled"] is True
    assert policy["allowlist"] == ["important-override.example"]
    assert policy["blocklist"] == ["tracker.example.com"]
    assert policy["category_allow"] == ["education"]
    assert policy["category_block"] == ["adult-content", "gambling"]
    status, fetched = client.get(f"/api/policies/{policy['id']}")
    assert status == 200
    assert fetched == policy


def test_create_rejects_bad_default(client):
    status, body = client.post("/api/policies", make_payload(default_policy="maybe"))
    assert status == 400
    assert "default_policy" in body["error"]


def test_create_rejects_bad_domain_in_allowlist(client):
    status, body = client.post("/api/policies", make_payload(allowlist=["not a domain"]))
    assert status == 400
    assert "allowlist" in body["error"]


def test_create_rejects_category_in_both_allow_and_block(client):
    status, body = client.post(
        "/api/policies", make_payload(category_allow=["news"], category_block=["news"])
    )
    assert status == 400
    assert "both" in body["error"]


def test_create_rejects_empty_name_and_long_values(client):
    status, _ = client.post("/api/policies", make_payload(name="  "))
    assert status == 400
    status, _ = client.post("/api/policies", make_payload(name="x" * 81))
    assert status == 400


def test_duplicate_name_rejected(client):
    create(client)
    status, body = client.post("/api/policies", make_payload())
    assert status == 409
    assert "already exists" in body["error"]


def test_list_search_and_enabled_filter(client):
    create(client)
    create(client, name="Strict shul", default_policy="block", enabled=False)
    status, body = client.get("/api/policies")
    assert len(body["policies"]) == 2
    status, body = client.get("/api/policies?search=shul")
    assert [p["name"] for p in body["policies"]] == ["Strict shul"]
    status, body = client.get("/api/policies?enabled=true")
    assert [p["name"] for p in body["policies"]] == ["Family baseline"]
    status, body = client.get("/api/policies?enabled=false")
    assert [p["name"] for p in body["policies"]] == ["Strict shul"]


def test_get_missing_policy_404(client):
    status, _ = client.get("/api/policies/9999")
    assert status == 404


def test_update_policy(client):
    policy = create(client)
    status, updated = client.put(
        f"/api/policies/{policy['id']}",
        make_payload(name="Family updated", blocklist=["tracker.example.com", "ads.example"],
                     category_block=["gambling"]),
    )
    assert status == 200, updated
    assert updated["name"] == "Family updated"
    assert updated["blocklist"] == ["ads.example", "tracker.example.com"]
    assert updated["category_block"] == ["gambling"]
    status, fetched = client.get(f"/api/policies/{policy['id']}")
    assert fetched["name"] == "Family updated"


def test_update_missing_policy_404(client):
    status, _ = client.put("/api/policies/9999", make_payload())
    assert status == 404


def test_update_to_duplicate_name_rejected(client):
    create(client)
    second = create(client, name="Other policy")
    status, body = client.put(f"/api/policies/{second['id']}", make_payload())
    assert status == 409


def test_update_with_conflicting_category_rules_rejected(client):
    policy = create(client)
    status, body = client.put(
        f"/api/policies/{policy['id']}",
        make_payload(category_allow=["news"], category_block=["news"]),
    )
    assert status == 400
    # The stored policy is unchanged.
    status, fetched = client.get(f"/api/policies/{policy['id']}")
    assert fetched["category_block"] == ["adult-content", "gambling"]


def test_enable_disable_toggle(client):
    policy = create(client)
    status, body = client.post(f"/api/policies/{policy['id']}/enabled", {"enabled": False})
    assert status == 200
    assert body["enabled"] is False
    status, body = client.post(f"/api/policies/{policy['id']}/enabled", {"enabled": "yes"})
    assert status == 400
    status, body = client.post(f"/api/policies/{policy['id']}/enabled", {"enabled": True})
    assert body["enabled"] is True
    status, _ = client.post("/api/policies/9999/enabled", {"enabled": True})
    assert status == 404


def test_delete_policy(client):
    policy = create(client)
    status, _ = client.delete(f"/api/policies/{policy['id']}")
    assert status == 200
    status, _ = client.get(f"/api/policies/{policy['id']}")
    assert status == 404
    status, _ = client.delete(f"/api/policies/{policy['id']}")
    assert status == 404


def test_duplicate_allowlist_entries_deduped(client):
    policy = create(client, allowlist=["a.example", "a.example", "b.example"])
    assert policy["allowlist"] == ["a.example", "b.example"]
