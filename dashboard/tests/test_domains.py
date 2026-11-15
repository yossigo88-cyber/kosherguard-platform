"""Domain management tests."""


def add(client, domain, categories, rule=None):
    status, body = client.post(
        "/api/domains", {"domain": domain, "categories": categories, "rule": rule}
    )
    assert status == 201, body
    return body


def test_create_domain(client):
    body = add(client, "bbc.example", ["news"])
    assert body["domain"] == "bbc.example"
    assert body["categories"] == ["news"]
    assert body["rule"] is None
    status, fetched = client.get("/api/domains/bbc.example")
    assert status == 200
    assert fetched == body


def test_create_rejects_malformed_domain(client):
    for bad in ("not a domain", "no-tld", "-bad.example", "bad-.example", ""):
        status, body = client.post("/api/domains", {"domain": bad, "categories": ["news"]})
        assert status == 400, bad
        assert "error" in body


def test_create_rejects_non_string_domain(client):
    status, body = client.post("/api/domains", {"domain": 42, "categories": ["news"]})
    assert status == 400


def test_create_rejects_unknown_category(client):
    status, body = client.post("/api/domains", {
        "domain": "a.example", "categories": ["no-such-category"]})
    assert status == 400
    assert "does not exist" in body["error"]


def test_create_rejects_empty_categories(client):
    status, _ = client.post("/api/domains", {"domain": "a.example", "categories": []})
    assert status == 400


def test_create_rejects_duplicate(client):
    add(client, "bbc.example", ["news"])
    status, body = client.post("/api/domains", {"domain": "bbc.example", "categories": ["news"]})
    assert status == 409


def test_create_rejects_bad_rule(client):
    status, _ = client.post("/api/domains", {
        "domain": "a.example", "categories": ["news"], "rule": "sometimes"})
    assert status == 400


def test_explicit_rule_stored(client):
    body = add(client, "special.example", ["news"], rule="allow")
    assert body["rule"] == "allow"


def test_update_domain_categories_and_rule(client):
    add(client, "bbc.example", ["news"])
    status, body = client.put("/api/domains/bbc.example", {
        "categories": ["news", "search-engines"], "rule": "block"})
    assert status == 200
    assert body["categories"] == ["news", "search-engines"]
    assert body["rule"] == "block"
    status, fetched = client.get("/api/domains/bbc.example")
    assert fetched["rule"] == "block"


def test_update_missing_domain_404(client):
    status, _ = client.put("/api/domains/no.example", {"categories": ["news"]})
    assert status == 404


def test_delete_domain(client):
    add(client, "bbc.example", ["news"])
    status, _ = client.delete("/api/domains/bbc.example")
    assert status == 200
    status, _ = client.get("/api/domains/bbc.example")
    assert status == 404
    status, _ = client.delete("/api/domains/bbc.example")
    assert status == 404


def test_search_and_filters(client):
    add(client, "bbc.example", ["news"])
    add(client, "cnn.example", ["news"], rule="block")
    add(client, "shop.example", ["shopping"], rule="allow")
    status, body = client.get("/api/domains?search=bbc")
    assert [d["domain"] for d in body["domains"]] == ["bbc.example"]
    status, body = client.get("/api/domains?category=news")
    assert {d["domain"] for d in body["domains"]} == {"bbc.example", "cnn.example"}
    status, body = client.get("/api/domains?rule=allow")
    assert [d["domain"] for d in body["domains"]] == ["shop.example"]


def test_domain_normalization(client):
    add(client, "BBC.EXAMPLE.", ["news"])
    status, body = client.get("/api/domains?search=bbc")
    assert [d["domain"] for d in body["domains"]] == ["bbc.example"]
