"""Security tests: CSRF, body limits, injection handling, traversal,
response headers, and information exposure."""

import http.client
import json


def test_csrf_header_required_on_mutations(client):
    for method, path in (("POST", "/api/policies"), ("PUT", "/api/policies/1"),
                         ("DELETE", "/api/policies/1"), ("POST", "/api/domains"),
                         ("POST", "/api/logout")):
        status, body = client.request(method, path, {"name": "x"}, csrf=False)[:2]
        assert status == 403, (method, path)
        assert "X-KosherGuard-Request" in body["error"]


def test_oversized_body_rejected(client):
    # Announce a 2 MB body; the server must reject from Content-Length
    # alone, without waiting for the bytes.
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.putrequest("POST", "/api/policies")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(2 * 1024 * 1024))
    conn.putheader("X-KosherGuard-Request", "1")
    conn.putheader("Cookie", client.cookie)
    conn.endheaders()
    response = conn.getresponse()
    assert response.status == 413
    response.read()
    conn.close()


def test_invalid_json_rejected(client):
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("POST", "/api/policies", "{not json", {
        "Content-Type": "application/json",
        "X-KosherGuard-Request": "1",
        "Cookie": client.cookie,
    })
    response = conn.getresponse()
    assert response.status == 400
    response.read()
    conn.close()


def test_non_object_body_rejected(client):
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("POST", "/api/policies", "[1, 2, 3]", {
        "Content-Type": "application/json",
        "X-KosherGuard-Request": "1",
        "Cookie": client.cookie,
    })
    response = conn.getresponse()
    assert response.status == 400
    response.read()
    conn.close()


def test_sql_injection_strings_are_plain_data(client):
    # Classic injection probes must be treated as inert data.
    probe = "'; DROP TABLE policies; --"
    status, body = client.get(f"/api/policies?search={probe.replace(' ', '%20')}")
    assert status == 200
    assert body["policies"] == []
    status, body = client.post("/api/policies", {
        "name": probe, "default_policy": "allow"})
    assert status == 201
    status, body = client.get("/api/policies")
    assert body["policies"][0]["name"] == probe
    # The table still exists and works.
    status, body = client.get("/api/overview")
    assert body["policies"] == 1


def test_static_traversal_rejected(client):
    for path in ("/../src/server.py", "/static/..%2f..%2fsrc%2fserver.py",
                 "/%2e%2e/%2e%2e/etc/passwd"):
        status, _ = client.get(path)
        assert status in (400, 404), path
    # Source files are never served.
    status, _ = client.get("/src/server.py")
    assert status == 404


def test_security_headers_present(client):
    status, body, headers, _ = client.request("GET", "/api/me")
    header_map = {k.lower(): v for k, v in headers}
    assert header_map.get("x-content-type-options") == "nosniff"
    assert header_map.get("x-frame-options") == "DENY"
    assert header_map.get("cache-control") == "no-store"


def test_html_has_content_security_policy(client):
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("GET", "/")
    response = conn.getresponse()
    headers = {k.lower(): v for k, v in response.getheaders()}
    response.read()
    conn.close()
    assert response.status == 200
    assert "content-security-policy" in headers
    assert "default-src 'self'" in headers["content-security-policy"]


def test_unknown_api_route_404(client):
    status, _ = client.get("/api/no-such-thing")
    assert status == 404


def test_error_shape_is_consistent(client):
    status, body = client.get("/api/policies/9999")
    assert status == 404
    assert set(body.keys()) == {"error"}
    status, body = client.post("/api/policies", {"name": "x"})
    assert status == 400
    assert set(body.keys()) == {"error"}


def test_login_body_types_validated(anon_client):
    status, _ = anon_client.post("/api/login", {"username": 1, "password": "x"})
    assert status == 400


def test_no_secrets_in_static_or_api(client):
    # The interface must not ship any password or hash.
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    for path in ("/", "/styles.css", "/app.js"):
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace")
        assert response.status == 200, path
        assert "password_hash" not in body
        assert "pbkdf2$" not in body
    conn.close()
