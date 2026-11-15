"""Category management tests."""


def test_seed_categories_exist(client):
    status, body = client.get("/api/categories")
    assert status == 200
    names = [c["name"] for c in body["categories"]]
    for expected in ("adult-content", "gambling", "social-media", "video-streaming",
                     "games", "shopping", "news", "search-engines", "messaging",
                     "file-sharing", "malware-phishing"):
        assert expected in names
    for category in body["categories"]:
        assert category["builtin"] == 1
        assert category["domain_count"] == 0


def test_create_custom_category(client):
    status, body = client.post("/api/categories", {
        "name": "torah-study", "display_name": "Torah study",
        "description": "Torah and Jewish learning sites.",
    })
    assert status == 201, body
    assert body["builtin"] == 0
    assert body["enabled"] == 1
    status, body = client.get("/api/categories?search=torah")
    assert [c["name"] for c in body["categories"]] == ["torah-study"]


def test_create_rejects_invalid_slug(client):
    status, body = client.post("/api/categories", {
        "name": "Not A Slug!", "display_name": "Bad"})
    assert status == 400
    assert "name" in body["error"]


def test_create_rejects_duplicate(client):
    status, body = client.post("/api/categories", {
        "name": "news", "display_name": "News again"})
    assert status == 409


def test_create_defaults_enabled_when_omitted(client):
    status, body = client.post("/api/categories", {
        "name": "default-on", "display_name": "Default on"})
    assert status == 201, body
    assert body["enabled"] == 1


def test_create_accepts_real_boolean_false(client):
    status, body = client.post("/api/categories", {
        "name": "starts-off", "display_name": "Starts off", "enabled": False})
    assert status == 201, body
    assert body["enabled"] == 0
    status, body = client.get("/api/categories?search=starts-off")
    assert body["categories"][0]["enabled"] == 0


def test_create_rejects_string_false(client):
    status, body = client.post("/api/categories", {
        "name": "string-false", "display_name": "String false", "enabled": "false"})
    assert status == 400
    assert "enabled" in body["error"]
    status, body = client.get("/api/categories?search=string-false")
    assert body["categories"] == []


def test_create_rejects_string_true(client):
    status, body = client.post("/api/categories", {
        "name": "string-true", "display_name": "String true", "enabled": "true"})
    assert status == 400
    assert "enabled" in body["error"]


def test_create_rejects_integer_enabled(client):
    for value in (0, 1):
        status, body = client.post("/api/categories", {
            "name": f"int-{value}", "display_name": "Int", "enabled": value})
        assert status == 400, value
        assert "enabled" in body["error"]


def test_create_rejects_null_enabled(client):
    status, body = client.post("/api/categories", {
        "name": "null-enabled", "display_name": "Null", "enabled": None})
    assert status == 400
    assert "enabled" in body["error"]


def test_invalid_enabled_writes_no_audit_entry(client):
    status, body = client.get("/api/audit")
    before = [e for e in body["entries"] if e["action"] == "category.create"]
    for value in ("false", "true", 0, 1, None):
        status, _ = client.post("/api/categories", {
            "name": "no-audit", "display_name": "No audit", "enabled": value})
        assert status == 400, value
    status, body = client.get("/api/audit")
    after = [e for e in body["entries"] if e["action"] == "category.create"]
    assert after == before
    status, body = client.get("/api/categories?search=no-audit")
    assert body["categories"] == []


def test_update_display_name_and_description(client):
    status, body = client.put("/api/categories/news", {
        "display_name": "News and current events",
        "description": "Updated description.",
    })
    assert status == 200
    assert body["display_name"] == "News and current events"
    status, body = client.get("/api/categories?search=current%20events")
    assert body["categories"][0]["name"] == "news"


def test_update_missing_category_404(client):
    status, _ = client.put("/api/categories/no-such", {"display_name": "X"})
    assert status == 404


def test_enable_disable_category(client):
    status, body = client.post("/api/categories/games/enabled", {"enabled": False})
    assert status == 200
    assert body["enabled"] == 0
    status, body = client.post("/api/categories/games/enabled", {"enabled": "yes"})
    assert status == 400
    status, body = client.post("/api/categories/games/enabled", {"enabled": True})
    assert body["enabled"] == 1
    status, _ = client.post("/api/categories/no-such/enabled", {"enabled": True})
    assert status == 404


def test_domain_count_updates(client):
    client.post("/api/domains", {"domain": "bbc.example", "categories": ["news"]})
    client.post("/api/domains", {"domain": "cnn.example", "categories": ["news", "shopping"]})
    status, body = client.get("/api/categories")
    counts = {c["name"]: c["domain_count"] for c in body["categories"]}
    assert counts["news"] == 2
    assert counts["shopping"] == 1
    assert counts["games"] == 0
