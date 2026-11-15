"""Import process tests: engine-reused validation, atomic abort,
line-numbered errors, category existence enforcement."""


def test_import_adds_and_updates(client):
    client.post("/api/domains", {"domain": "bbc.example", "categories": ["news"]})
    status, body = client.post("/api/domains/import", {"records": [
        {"domain": "bbc.example", "categories": ["search-engines"]},
        {"domain": "cnn.example", "categories": ["news"]},
    ]})
    assert status == 200, body
    assert body == {"records": 2, "added": 1, "updated": 1}
    status, fetched = client.get("/api/domains/bbc.example")
    # Categories union onto the existing record.
    assert fetched["categories"] == ["news", "search-engines"]


def test_import_rejects_malformed_domain_with_line_number(client):
    status, body = client.post("/api/domains/import", {"records": [
        {"domain": "fine.example", "categories": ["news"]},
        {"domain": "not a domain", "categories": ["news"]},
    ]})
    assert status == 400
    assert "import line 2" in body["error"]


def test_import_is_atomic(client):
    status, _ = client.post("/api/domains/import", {"records": [
        {"domain": "fine.example", "categories": ["news"]},
        {"domain": "broken", "categories": ["news"]},
    ]})
    assert status == 400
    # Nothing was applied: the valid first record was rolled back too.
    status, body = client.get("/api/domains")
    assert body["domains"] == []


def test_import_rejects_non_string_domain(client):
    status, body = client.post("/api/domains/import", {"records": [
        {"domain": 42, "categories": ["news"]}]})
    assert status == 400
    assert "import line 1" in body["error"]


def test_import_rejects_non_list_categories(client):
    status, _ = client.post("/api/domains/import", {"records": [
        {"domain": "a.example", "categories": "news"}]})
    assert status == 400


def test_import_rejects_unknown_categories(client):
    status, body = client.post("/api/domains/import", {"records": [
        {"domain": "a.example", "categories": ["no-such-category"]}]})
    assert status == 400
    assert "no-such-category" in body["error"]
    status, body = client.get("/api/domains")
    assert body["domains"] == []


def test_import_rejects_empty_records(client):
    status, _ = client.post("/api/domains/import", {"records": []})
    assert status == 400


def test_import_rejects_missing_fields(client):
    status, body = client.post("/api/domains/import", {"records": [{"categories": ["news"]}]})
    assert status == 400
    assert "import line 1" in body["error"]


def test_import_jsonl_format(client):
    jsonl = '{"domain": "jsonl.example", "categories": ["games"]}\n' \
            '{"domain": "jsonl2.example", "categories": ["news", "games"]}\n'
    status, body = client.post("/api/domains/import", {"jsonl": jsonl})
    assert status == 200, body
    assert body["added"] == 2
    status, fetched = client.get("/api/domains/jsonl2.example")
    assert fetched["categories"] == ["games", "news"]


def test_import_jsonl_bad_line(client):
    jsonl = '{"domain": "ok.example", "categories": ["news"]}\nnot json\n'
    status, body = client.post("/api/domains/import", {"jsonl": jsonl})
    assert status == 400
    assert "import line 2" in body["error"]
    status, body = client.get("/api/domains")
    assert body["domains"] == []
